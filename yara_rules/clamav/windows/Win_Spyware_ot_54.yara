rule Win_Spyware_ot_54
{
strings:
	$a0 = { a923bf99338d1fb9a35f1f33a13a5433336d33d24bc0d023231a8d5d8903ffd913cdff79631fdff3616094f3f3758ff3f3df570b16a4cfe38eebf303e3cf3ef2ef9880c3c34af2cf17bfafc34a8d6cb9071f5ed2cfc0d02323aab2af54e40f238a }

condition:
	$a0
}

        
