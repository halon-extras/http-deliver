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
