rule Win_Trojan_Small_210
{
strings:
	$a0 = { 0e404ffb34890a1c8651c3a1280740aeee432809047bdf447f3db5bdbb3a59372ce8aeaff9e85730b162b0a78cbe94c842874de9f107f1a8b7d0798ac62e92d654bf4849bb66f718e3aaa9b13ef22121 }

condition:
	$a0
}

        
