rule Win_Trojan_Bancos_1385
{
strings:
	$a0 = { cb2befbd8d7caf49be4fe34cd68322d6558bc840b152f752d9e3045464be66d36a77ecf6fe1b395aa30294db6f919a5287b3be6c07a1c589cf5aad7e00a5786eea83d2a9689fba2856344def6c2e191f1dc4d22b704805a009ef83eaabc56c9255cc2becc546734b }

condition:
	$a0
}

        
