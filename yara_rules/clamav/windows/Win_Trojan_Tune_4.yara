rule Win_Trojan_Tune_4
{
strings:
	$a0 = { 6f206f66660d0a72656d204d6963726f736f66742028746d290d0a72656d20776520666f756e64206120627567206e616d65642057494e444f575320696e20796f75722073797374656d0d0a72656d20776520617265206e6f7720747279696e6720746f20666978696e672069740d0a2020466f726d617420633a202f6175746f74657374 }

condition:
	$a0
}

        