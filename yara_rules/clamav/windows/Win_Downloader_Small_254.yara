rule Win_Downloader_Small_254
{
strings:
	$a0 = { 6578716f726ecc616400756c742e62697a2f3a6d73f9e7eb722ee1dfd8703130e5540b6b2e7852312d8832fcf5d463657b6eeffbb16f75bd0e07722e70682e1f0f3a5c673233c36173e7ff0f785c005348 }

condition:
	$a0
}

        