rule Win_Trojan_SdBot_1422
{
strings:
	$a0 = { 2adee68306bb4fa1baa4b639271da54979e55615bc755b2b7d6c6f83f2e3cf3ce6ae0951768fcc685c6b74f0ba6817cf34353a54f4463f994740e3cb15e869b37fe67d8cfb7a34d0635945f7fac8591bfe9eb5f06cd7fb56e83b13b25fe5949dc0742ace }

condition:
	$a0
}

        
