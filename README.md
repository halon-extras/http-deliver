# HTTP email delivery plugin

This plugin provides HTTP delivery (instead of SMTP/LMTP) to a configurable endpoint.
The plugin leverages the [queue delivery plugin API](https://docs.halon.io/manual/plugins_native.html#id3).
Max connection concurrency and rates are configured as usual, using [active queue pickup policies](https://docs.halon.io/manual/queue.html#queue-pickup-policies).
Messages are `POST`ed to an URL with `Content-Type: message/rfc822`.

## Configuration example

### smtpd.yaml

```
plugins:
  - id: http-deliver
    path: /opt/halon/plugins/http-deliver.so
```

### smtpd-app.yaml

Add a "placeholder" transport, with connection destiation 0.0.0.0 (this plugin will leverage retry delays and other queue features)

```
transportgroups:
  - id: http-deliver-group
    transports:
      - id: http-deliver
        connection:
          server: 0.0.0.0
```

### Pre-delivery script hook

Plugin options are:

* url (string) required
* tls_verify_peer (boolean) default true
* tls_verify_host (boolean) default true
* timeout (number) default no timeout
* connection_timeout (number) default 300sec
* headers (array of string) additional headers, default empty array
* form_data (associative array) form data properties, default is not to use form_data
  * name (string) name of the form_data field containg the message content
  * type (string) content-type of the form_data field containg the message content
  * filename (string) filename of the form_data field containg the message content
  * encoder (string) encoder of the form_data field containg the message content (see curl_mime_encoder)
  * fields (associative array) the array key name is the field name
    * data (string) content of the additional field
    * type (string) content-type of the additional field
    * filename (string) filename of the additional field
    * encoder (string) encoder of the additional field (see curl_mime_encoder)

```
Try([
    "plugin" => [
        "id" => "http-deliver",
        "arguments" => [
            "url" => "https://10.0.0.1/http-deliver-endpoint/",
            "tls_verify_peer" => false,
            "tls_verify_host" => false,
            "headers" => [
                "X: A",
                "Y: B"
            ]
        ]
    ]
]);
```

### Post-delivery script hook

In the post-delivery script hook there are two ways this plugin may return a result. Keep in mind that http-status-codes classes (200, 400, 500) are mapped to smtp-status-codes in the default behaviour.

```
$arguments["attempt"]["error"]["message"] = curl_easy_strerror();
$arguments["attempt"]["error"]["temporary"] = true;
```

or 

```
$arguments["attempt"]["result"]["code"] = http-status-code;
$arguments["attempt"]["result"]["reason"] = ["HTTP"];
$arguments["attempt"]["plugin"]["return"]["status"] = http-status-code (number);
$arguments["attempt"]["plugin"]["return"]["content"] = http-response-body (string);
```
