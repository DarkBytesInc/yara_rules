rule Win_Proxy_Agent_34872
{
strings:
	$a0 = { a5015cec04619d1c7ecaec17b388c6fb11b22f0f75fc76f1b9a15c689767306864deea985ee8f99f822870add5204e0e1caa5c4905eca845782b8f6b5993b8baf823f3fdbb229d1ab426b539a6874547e2cefaa39a5b7e2427d6c59d80a9d4170e1f55bed48208cbd5aae317437fa4ec729a2e08b476b0d2b877ae }

condition:
	$a0
}

        