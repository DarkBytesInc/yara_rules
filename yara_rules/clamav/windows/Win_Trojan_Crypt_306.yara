rule Win_Trojan_Crypt_306
{
strings:
	$a0 = { 558bec81c474ffffff68796d5800e85504000068f7433bf4e80cfdffff0bc00f84dd010000c36878a6c986683e7638d4e852fdffffffb5d0feffffffb520feffffffb5ccfeffff8d8d04feffff51e8fa030000e8d7fcffff68443500006a47ffb518ffffff8d8d7cfeffff51e8c2020000e8e2050000576a00e822040000be4f }

condition:
	$a0
}

        
