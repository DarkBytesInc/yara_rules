rule Win_Trojan_SdBot_3844
{
strings:
	$a0 = { 58d3d6aa0e1ad622d2fda770c6e10146448bf5d585e93a9f5f9caf0ec3989d5597ce92fd7fafbb88070eab94efadea70af712c6be0f574d9af86db8cc3446db9b6442da3383fb271459900ffd2968e590352f2f354be3fd62eb1f693b363bb9f14cd }

condition:
	$a0
}

        
