rule Win_Trojan_SdBot_2313
{
strings:
	$a0 = { e4b06a901c10ec19ed1792bbf9445a8f61a1a2d11e42181a7d7318652854d4f23883c8b2ddb058910f78a4b78c676704e9352f73f4b5c5454e243fa5019aa56e24490be4c74f1dc9d93d0801558d01f6191588ad9ed670e794259d992d2a9e50d3dda4247a6b2cceb3fcd1a801c89840dde008cb3983a8dead7b }

condition:
	$a0
}

        