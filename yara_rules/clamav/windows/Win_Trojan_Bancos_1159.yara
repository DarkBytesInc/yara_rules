rule Win_Trojan_Bancos_1159
{
strings:
	$a0 = { e372c62b5f6d0a6e2ab0be08eebde0af4eebca62f1eb3878941284a02a6be8103d2e62306dba2b19c3fd6a203627ddecf85395dc736803601fa7214d2f751341668375ac9a4521ca896db8abe79ef1e452d4659bf7c270b4ad35b79302b1cc }

condition:
	$a0
}

        
