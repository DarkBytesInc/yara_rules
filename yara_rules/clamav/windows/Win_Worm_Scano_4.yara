rule Win_Worm_Scano_4
{
strings:
	$a0 = { f1b0f5bd800a01aff36a22d282e5db587430a36d0548d30b28591700a80e5f5249b0543b26afc86aaa21e59ddbe1390196a5a93a326b6142353e39a3eea383ea476f06bf88fe6c5be119b5d1027407edc10bb8543b50ea729d8e30732d9ae75b4753c4cae09ede1035988550e158dc628511490e1c68df91ff91af6a1249d8d79f4e35371ff24c9e84f70d173af9071eeb406ce2 }

condition:
	$a0
}

        