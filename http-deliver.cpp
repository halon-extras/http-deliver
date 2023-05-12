#include <HalonMTA.h>
#include <string>
#include <thread>
#include <queue>
#include <mutex>
#include <cstring>
#include <curl/curl.h>
#include <openssl/evp.h>

std::thread tid;
bool quit = false;
CURLM *multi_handle = nullptr;
std::mutex lock;
std::queue<CURL*> curls;

struct halon {
	HalonDeliverContext *hdc;
	struct curl_slist *headers = nullptr;
	curl_mime *mime = nullptr;
	void *user;
	EVP_ENCODE_CTX *evp = nullptr;
	FILE *fp = nullptr;
};

void curl_multi()
{
	do {
		CURLMcode mc;

		int still_running;
		mc = curl_multi_perform(multi_handle, &still_running);

		struct CURLMsg *m;
		do {
			int msgq = 0;
			m = curl_multi_info_read(multi_handle, &msgq);
			if (m && (m->msg == CURLMSG_DONE))
			{
				CURL *e = m->easy_handle;

				halon *h;
				curl_easy_getinfo(e, CURLINFO_PRIVATE, &h);

				if (m->data.result != CURLE_OK)
				{
					HalonMTA_deliver_setinfo(h->hdc, HALONMTA_ERROR_REASON, curl_easy_strerror(m->data.result), 0);
				}
				else
				{
					long status;
					curl_easy_getinfo(e, CURLINFO_RESPONSE_CODE, &status);

					/* build ["attempt"]["result"] */
					HalonMTA_deliver_setinfo(h->hdc, HALONMTA_RESULT_CODE, &status, 0);
					HalonMTA_deliver_setinfo(h->hdc, HALONMTA_RESULT_REASON, "HTTP", 0);

					/* build ["attempt"]["plugin"]["return"] */
					HalonHSLValue *k, *v;
					HalonHSLValue *ret;
					HalonMTA_deliver_getinfo(h->hdc, HALONMTA_INFO_RETURN, NULL, 0, &ret, NULL);
					HalonMTA_hsl_value_array_add(ret, &k, &v);
					HalonMTA_hsl_value_set(k, HALONMTA_HSL_TYPE_STRING, "status", 0);
					double status_ = status;
					HalonMTA_hsl_value_set(v, HALONMTA_HSL_TYPE_NUMBER, &status_, 0);
					HalonMTA_hsl_value_array_add(ret, &k, &v);
					HalonMTA_hsl_value_set(k, HALONMTA_HSL_TYPE_STRING, "content", 0);
					HalonMTA_hsl_value_set(v, HALONMTA_HSL_TYPE_STRING, ((std::string*)h->user)->c_str(), 0);
				}

				HalonMTA_deliver_done(h->hdc);
				delete (std::string*)h->user;
				curl_slist_free_all(h->headers);
				curl_mime_free(h->mime);
				EVP_ENCODE_CTX_free(h->evp);
				delete h;

				curl_multi_remove_handle(multi_handle, e);
				curl_easy_cleanup(e);
			}
		} while (m);

		int numfds;
		mc = curl_multi_poll(multi_handle, nullptr, 0, 10000, &numfds);

		lock.lock();
		while (!curls.empty())
		{
			CURL *curl = curls.front();
			curl_multi_add_handle(multi_handle, curl);
			curls.pop();
		}
		lock.unlock();
	} while (!quit);
}

HALON_EXPORT
int Halon_version()
{
	return HALONMTA_PLUGIN_VERSION;
}

HALON_EXPORT
bool Halon_init(HalonInitContext *hic)
{
	curl_global_init(CURL_GLOBAL_DEFAULT);
	multi_handle = curl_multi_init();

	tid = std::thread(curl_multi);
	return true;
}

HALON_EXPORT
void Halon_cleanup()
{
	quit = true;
	curl_multi_wakeup(multi_handle);
	tid.join();
}

size_t read_callback(char *dest, size_t size, size_t nmemb, FILE *fp)
{
	size_t x = fread(dest, size, nmemb, fp);
	return x;
}

size_t read_callback_evp(char *dest, size_t size, size_t nmemb, halon *h)
{
	unsigned char buf[65524 / 2]; // XXX: large safety margin
	size_t x = fread(buf, 1, sizeof(buf), h->fp);
	int destlen;
	if (x == 0)
		EVP_EncodeFinal(h->evp, (unsigned char*)dest, &destlen);
	else
		EVP_EncodeUpdate(h->evp, (unsigned char*)dest, &destlen, buf, (int)x);
	return destlen;
}

size_t write_callback(char *data, size_t size, size_t nmemb, std::string *writerData)
{
	if (writerData == nullptr)
		return 0;
	writerData->append((const char*)data, size * nmemb);
	return size * nmemb;
}

HALON_EXPORT
void Halon_deliver(HalonDeliverContext *hdc)
{
	FILE *fp = nullptr;
	if (!HalonMTA_deliver_getinfo(hdc, HALONMTA_INFO_FILE, nullptr, 0, (void*)&fp, nullptr))
	{
		HalonMTA_deliver_setinfo(hdc, HALONMTA_ERROR_REASON, "No file (internal error)", 0);
		HalonMTA_deliver_done(hdc);
		return;
	}

	const HalonHSLValue *arguments = nullptr;
	if (!HalonMTA_deliver_getinfo(hdc, HALONMTA_INFO_ARGUMENTS, nullptr, 0, &arguments, nullptr))
	{
		HalonMTA_deliver_setinfo(hdc, HALONMTA_ERROR_REASON, "No argument", 0);
		HalonMTA_deliver_done(hdc);
		return;
	}

	const char *url = nullptr;
	const HalonHSLValue *hv_url = HalonMTA_hsl_value_array_find(arguments, "url");
	if (!hv_url || !HalonMTA_hsl_value_get(hv_url, HALONMTA_HSL_TYPE_STRING, &url, nullptr))
	{
		HalonMTA_deliver_setinfo(hdc, HALONMTA_ERROR_REASON, "No URL", 0);
		HalonMTA_deliver_done(hdc);
		return;
	}

	bool tls_verify_peer = true;
	const HalonHSLValue *hv_tls_verify_peer = HalonMTA_hsl_value_array_find(arguments, "tls_verify_peer");
	if (hv_tls_verify_peer && !HalonMTA_hsl_value_get(hv_tls_verify_peer, HALONMTA_HSL_TYPE_BOOLEAN, &tls_verify_peer, nullptr))
	{
		HalonMTA_deliver_setinfo(hdc, HALONMTA_ERROR_REASON, "Bad tls_verify_peer value", 0);
		HalonMTA_deliver_done(hdc);
		return;
	}

	bool tls_verify_host = true;
	const HalonHSLValue *hv_tls_verify_host = HalonMTA_hsl_value_array_find(arguments, "tls_verify_host");
	if (hv_tls_verify_host && !HalonMTA_hsl_value_get(hv_tls_verify_host, HALONMTA_HSL_TYPE_BOOLEAN, &tls_verify_host, nullptr))
	{
		HalonMTA_deliver_setinfo(hdc, HALONMTA_ERROR_REASON, "Bad tls_verify_host value", 0);
		HalonMTA_deliver_done(hdc);
		return;
	}

	long timeout = 0;
	const HalonHSLValue *hv_timeout = HalonMTA_hsl_value_array_find(arguments, "timeout");
	if (hv_timeout)
	{
		double timeout_;
		if (!HalonMTA_hsl_value_get(hv_timeout, HALONMTA_HSL_TYPE_NUMBER, &timeout_, nullptr))
		{
			HalonMTA_deliver_setinfo(hdc, HALONMTA_ERROR_REASON, "Bad timeout value", 0);
			HalonMTA_deliver_done(hdc);
			return;
		}
		timeout = (long)timeout_;
	}

	long connect_timeout = 0;
	const HalonHSLValue *hv_connect_timeout = HalonMTA_hsl_value_array_find(arguments, "connect_timeout");
	if (hv_timeout)
	{
		double connect_timeout_;
		if (!HalonMTA_hsl_value_get(hv_connect_timeout, HALONMTA_HSL_TYPE_NUMBER, &connect_timeout_, nullptr))
		{
			HalonMTA_deliver_setinfo(hdc, HALONMTA_ERROR_REASON, "Bad connect_timeout value", 0);
			HalonMTA_deliver_done(hdc);
			return;
		}
		connect_timeout = (long)connect_timeout_;
	}

	const char *encoder = nullptr;
	const HalonHSLValue *hv_encoder = HalonMTA_hsl_value_array_find(arguments, "encoder");
	if (hv_encoder && !HalonMTA_hsl_value_get(hv_encoder, HALONMTA_HSL_TYPE_STRING, &encoder, nullptr))
	{
		HalonMTA_deliver_setinfo(hdc, HALONMTA_ERROR_REASON, "Bad encoder value", 0);
		HalonMTA_deliver_done(hdc);
		return;
	}
	bool base64_encode = encoder && strcmp(encoder, "base64") == 0;

	const char *proxy = nullptr;
	const HalonHSLValue *hv_proxy = HalonMTA_hsl_value_array_find(arguments, "proxy");
	if (hv_proxy && !HalonMTA_hsl_value_get(hv_proxy, HALONMTA_HSL_TYPE_STRING, &proxy, nullptr))
	{
		HalonMTA_deliver_setinfo(hdc, HALONMTA_ERROR_REASON, "Bad proxy value", 0);
		HalonMTA_deliver_done(hdc);
		return;
	}

	const char *method = nullptr;
	const HalonHSLValue *hv_method = HalonMTA_hsl_value_array_find(arguments, "method");
	if (hv_method && !HalonMTA_hsl_value_get(hv_method, HALONMTA_HSL_TYPE_STRING, &method, nullptr))
	{
		HalonMTA_deliver_setinfo(hdc, HALONMTA_ERROR_REASON, "Bad method value", 0);
		HalonMTA_deliver_done(hdc);
		return;
	}

	auto h = new halon;
	h->hdc = hdc;
	h->user = (void*)new std::string;

	CURL *curl = curl_easy_init();

	const HalonHSLValue *hv_form_data = HalonMTA_hsl_value_array_find(arguments, "form_data");
	if (hv_form_data)
	{
		h->mime = curl_mime_init(curl);
		const HalonHSLValue *hv_form_data_fields = HalonMTA_hsl_value_array_find(hv_form_data, "fields");
		if (hv_form_data_fields)
		{
			size_t index = 0;
			HalonHSLValue *k, *v;
			while ((v = HalonMTA_hsl_value_array_get(hv_form_data_fields, index, &k)))
			{
				curl_mimepart *field = curl_mime_addpart(h->mime);
				const char *data = nullptr;
				size_t datalen;

				if (HalonMTA_hsl_value_get(k, HALONMTA_HSL_TYPE_STRING, &data, nullptr))
					curl_mime_name(field, data);

				const HalonHSLValue *hv_field_data = HalonMTA_hsl_value_array_find(v, "data");
				if (HalonMTA_hsl_value_get(hv_field_data, HALONMTA_HSL_TYPE_STRING, &data, &datalen))
					curl_mime_data(field, data, datalen);

				const HalonHSLValue *hv_field_type = HalonMTA_hsl_value_array_find(v, "type");
				if (HalonMTA_hsl_value_get(hv_field_type, HALONMTA_HSL_TYPE_STRING, &data, &datalen))
					curl_mime_type(field, data);

				const HalonHSLValue *hv_field_filename = HalonMTA_hsl_value_array_find(v, "filename");
				if (HalonMTA_hsl_value_get(hv_field_filename, HALONMTA_HSL_TYPE_STRING, &data, &datalen))
					curl_mime_filename(field, data);

				const HalonHSLValue *hv_field_encoder = HalonMTA_hsl_value_array_find(hv_form_data, "encoder");
				if (HalonMTA_hsl_value_get(hv_field_encoder, HALONMTA_HSL_TYPE_STRING, &data, &datalen))
					curl_mime_encoder(field, data);

				++index;
			}
		}

		curl_mimepart *part = curl_mime_addpart(h->mime);
		const char *data = nullptr;
		size_t datalen;

		const HalonHSLValue *hv_name = HalonMTA_hsl_value_array_find(hv_form_data, "name");
		if (HalonMTA_hsl_value_get(hv_name, HALONMTA_HSL_TYPE_STRING, &data, &datalen))
			curl_mime_name(part, data);

		const HalonHSLValue *hv_type = HalonMTA_hsl_value_array_find(hv_form_data, "type");
		if (HalonMTA_hsl_value_get(hv_type, HALONMTA_HSL_TYPE_STRING, &data, &datalen))
			curl_mime_type(part, data);

		const HalonHSLValue *hv_filename = HalonMTA_hsl_value_array_find(hv_form_data, "filename");
		if (HalonMTA_hsl_value_get(hv_filename, HALONMTA_HSL_TYPE_STRING, &data, &datalen))
			curl_mime_filename(part, data);

		const HalonHSLValue *hv_encoder = HalonMTA_hsl_value_array_find(hv_form_data, "encoder");
		if (HalonMTA_hsl_value_get(hv_encoder, HALONMTA_HSL_TYPE_STRING, &data, &datalen))
			curl_mime_encoder(part, data);

		fseek(fp, 0, SEEK_END);
		size_t length = ftell(fp);
		fseek(fp, 0, SEEK_SET);
		curl_mime_data_cb(part, length, (curl_read_callback)fread, (curl_seek_callback)fseek, nullptr, (void*)fp);
	}

	bool hasContentType = false;
	const HalonHSLValue *hv_headers = HalonMTA_hsl_value_array_find(arguments, "headers");
	if (hv_headers)
	{
		size_t index = 0;
		HalonHSLValue *k, *v;
		while ((v = HalonMTA_hsl_value_array_get(hv_headers, index, &k)))
		{
			const char *header = nullptr;
			if (HalonMTA_hsl_value_get(v, HALONMTA_HSL_TYPE_STRING, &header, nullptr))
			{
				if (!hasContentType && strncasecmp(header, "Content-Type:", 13) == 0)
					hasContentType = true;
				h->headers = curl_slist_append(h->headers, header);
			}
			++index;
		}
	}

	if (!h->mime && !hasContentType)
		h->headers = curl_slist_append(h->headers, "Content-Type: message/rfc822");

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_PRIVATE, (void*)h);

	if (h->mime)
	{
		curl_easy_setopt(curl, CURLOPT_MIMEPOST, h->mime);
	}
	else
	{
		if (base64_encode)
		{
			h->fp = fp;
			h->evp = EVP_ENCODE_CTX_new();
			EVP_EncodeInit(h->evp);
			curl_easy_setopt(curl, CURLOPT_READFUNCTION, ::read_callback_evp);
			curl_easy_setopt(curl, CURLOPT_READDATA, (void*)h);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_READFUNCTION, ::read_callback);
			curl_easy_setopt(curl, CURLOPT_READDATA, (void*)fp);
		}
		curl_easy_setopt(curl, CURLOPT_POST, 1);
	}

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ::write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, h->user);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, h->headers);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);

	if (timeout)
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
	if (connect_timeout)
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, connect_timeout);
	if (!tls_verify_host)
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
	if (!tls_verify_peer)
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
	if (proxy)
		curl_easy_setopt(curl, CURLOPT_PROXY, proxy);
	if (method)
		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);

	lock.lock();
	curls.push(curl);
	curl_multi_wakeup(multi_handle);
	lock.unlock();
}
