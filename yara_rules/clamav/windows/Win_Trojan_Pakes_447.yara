rule Win_Trojan_Pakes_447
{
strings:
	$a0 = { 616c8bd815c45064d27265b8dc575521e190a527fd0401f1e1f8c0a03efb6a76f8a9abb5b85873030c046c9b5c0293aee5b8807b57d069b1ecc59c9acb9d683bc0fca795dcf817212dfe58ef8b2e7a7e32c96c2fee8e808921d9ab0d085ae5c769fd1fa88bd229edeca575a607ed872961b5a44843829215b87473600dfc73933bdea0524af8bf9b537dfcb7 }

condition:
	$a0
}

        