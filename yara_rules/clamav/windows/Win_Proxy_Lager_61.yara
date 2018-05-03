rule Win_Proxy_Lager_61
{
strings:
	$a0 = { 8be572eda0cc26154efce3263cb7174fab2197fd3e8b320597cf853c4231f62bae8476f27a5c0d855533ad32da7a2eacd673ca8ac486292e46b48cf0adb9b59a68c079512b1f }

condition:
	$a0
}

        
