rule Win_Trojan_Hupigon_827
{
strings:
	$a0 = { 7ab134ba4d9ad5e6d9c286fa1e353365386143fa0eda3fc3881d184d3869e07355039c9180a44191359a64cfde4bafd4f83e9f4d3e6bb3da2300c1f8a8de5739c3c91eec2e94f6c41ab61e3333dc28e1e6d6306a28a41cdedc3fd05596ddfb }

condition:
	$a0
}

        
