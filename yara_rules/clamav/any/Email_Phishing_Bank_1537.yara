rule Email_Phishing_Bank_1537
{
strings:
	$a0 = { 41707265732061766f69722066696e616c69736572206c6520666f726d756c61697265206176656320737563636573202c20756e206167656e74206465206e6f7472652062616e[0-10]71756520766f757320636f6e74616374657261207061722074656c6570686f6e6520706f75722076616c6964657220766f7320696e666f726d6174696f6e73 }

condition:
	$a0
}

        