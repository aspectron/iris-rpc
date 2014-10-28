var zrpc = require('../../../zetta-rpc');
var UUID = require('node-uuid');
var fs = require('fs');


var port = process.argv[2];
var serverPort = process.argv[3];

var auth = 'f72d7c54d7354f7a8f9d111c6033b6281e7096acc4dcb198763a4555f264259d';
var certificates = { key: '-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQDKbHuLTYtBLdAEjFe/DkrOm9FwmMlyjqDJO24NHIt4ZxIFY8qX\nQMlMTKQiyQPdDKgtOQsu04w91MtYJtJbtzKXpSr/erOefGNYHYDfE9XU2+/VfSEF\n3S6i8wCbAu2cNiB93ZBIQnAtt6sar7Q62h1VlMfe6XywFnRw7C0rHrCUpwIDAQAB\nAoGALFT/5a1Q7zBqW2SlHvmxVnh3sRI1JDqqagfy/TogLXldUALf7qpIq8YpOFkP\n2IyaFHVmxpWcJDqDYkX2UhHYKUwedQ/i+KdZ5M52mOP7iUHWC+5PYCYndJijVkdn\n1f1kaUDVGCEkrdXqgcB/7voj6rbqdcStVLc9XGAdrdEligkCQQDy4EXM3An9Z1pk\nBER5elaiRxQtjHUlL2h2XewzPnNIYLh4CLEY0m6XWj7Il1HlWdbkK4lFpBjGrYQv\n0jGLEXc1AkEA1VyhIW/D07afxqkLfpRCwN5SHWuIykSh/MnMdZMh6kORSxcrv/6v\nglYb061kDw5IploUVwrhrXNH4xOK/yFr6wJAWJ+xmKEqHAdcmmZcPh+AAVMCb+Ry\n0pDMA3UePUyqcFyqs1IonTAcHqpVgoiE37W6jiO8wWaxi73BIFoIrgA/iQJBAIi6\neY/B3c54w989SV5uiHCsiBbOaLSmUuB6OYpHJX7Imf1y9dhtz+9IW0DFZs+3KZth\nMpOtJ35N2A2O4o4ozs0CQGGPbkjxROSFuTzXmh8nWnFBi19W6IHjX6MY84TYRvol\nh5eXvetVF6dwIjAER5Zm3I036XUarbIoWnEzuUlOnWE=\n-----END RSA PRIVATE KEY-----\n',
    cert: '-----BEGIN CERTIFICATE-----\nMIICATCCAWoCCQDt1dDerT7q6DANBgkqhkiG9w0BAQUFADBFMQswCQYDVQQGEwJB\nVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0\ncyBQdHkgTHRkMB4XDTE0MDUwNjA3MjAzNloXDTMwMDMxNjIxNTUxNlowRTELMAkG\nA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0\nIFdpZGdpdHMgUHR5IEx0ZDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAymx7\ni02LQS3QBIxXvw5KzpvRcJjJco6gyTtuDRyLeGcSBWPKl0DJTEykIskD3QyoLTkL\nLtOMPdTLWCbSW7cyl6Uq/3qznnxjWB2A3xPV1Nvv1X0hBd0uovMAmwLtnDYgfd2Q\nSEJwLberGq+0OtodVZTH3ul8sBZ0cOwtKx6wlKcCAwEAATANBgkqhkiG9w0BAQUF\nAAOBgQBWSVHgxQPHGaQdVenAZlKdt+MR69Z224Ou+nmoXF49W1FThxc4oRG0t4xi\nNCglhytCiK/PcBvyt+3PyKYILD7PxUAsdmALq9nD+WG6rq7MIejfws7a6v5P7P/M\nfgQni0BRTefL5t3ZlxKGCgBR93gC/J8xoPe6DZzGytn+EMwW+A==\n-----END CERTIFICATE-----\n',
    ca: [] };

var uuid = UUID.v1();


var router = zrpc.Router({
    uuid: uuid,
    port : port,
    auth : auth,
    certificates : certificates,
    client : {
        uuid: uuid,
        address :  "127.0.0.1:" + serverPort,
//        node : self.mac
    }
});