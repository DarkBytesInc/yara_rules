rule Win_Trojan_Bancos_1236
{
strings:
	$a0 = { 2e4da967654fb46bc3744c98c3d64cc39915a15e2e22f98aec11ed75955f9e8a3d90ea602486aef2fed3f03e8de1b923991a571ee4f8537efe2bb2c4f0d9db61686d24d6dbde8d85a05bc1629eda667989fe61002b030c750c392c74a2c6ef }

condition:
	$a0
}

        
