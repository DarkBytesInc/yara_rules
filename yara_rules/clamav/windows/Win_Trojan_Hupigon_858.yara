rule Win_Trojan_Hupigon_858
{
strings:
	$a0 = { ddc87c8a0a2faa5434c91488c2b399f409ad70842c38caac9074873c2e7be23a3f4410ce0ee0292c27da3b6237e843164fc0bea1501ccacc3a21ebc99949d3481623d40bffb115e6913f4d7ef143ee567df8a3a98e80d4e79a5a8e7646d5a3 }

condition:
	$a0
}

        
