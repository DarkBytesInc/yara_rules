rule Win_Trojan_Avgan_1
{
strings:
	$a0 = { 756c0c633a5c6d73646f732e737973066c6f676f3d300a6175746f5363616e3d30343b91aaaeabecaaae20e7a5abaea2a5e7a5e1aaa8e520a6a8a7ada5a920e3e8abae20a220a0a2a3a0ade1aaaea920a2aea9ada53f9a00009f009a0d003d005589e531c09acd029f00bf52001e }

condition:
	$a0
}

        
