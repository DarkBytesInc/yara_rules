rule Win_Proxy_Xorpix_9
{
strings:
	$a0 = { c89770395a4bae2a43ee237775d0d2916d4bb6280ce3cbc6aa7944d3a5bb825f1a1ed0ef8457e9fe02dec9518e50daad78988a1199e58fe38a9e32885c6adc2bbd646459e0a66f3ed254c95057598f7fb4edda681fadb1923aacef4741473b6a5ba163c5c2a5ecf71355a1883b939a7ae861355bf0da27132f45069056118ca571563ff853c580e0f80afd075380100f }

condition:
	$a0
}

        