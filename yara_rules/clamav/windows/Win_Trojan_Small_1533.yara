rule Win_Trojan_Small_1533
{
strings:
	$a0 = { 38af5a913e569457433fed163f3f572a000f79a19cbfe9935be688f6491a7237bda558ac6bfac6284b0f39af68a124cdc9bd32e8c7b13fe9c6b23c303759cfe8daa632e6c5b236f6c7a235f5cf0fc3e66dbf3be3c4b8d0f84e4691136f5b961b4c0ed1887756925339a8e368cfc608e46d53473069fb3b47e3427f45cb0d5d8cf8e39012404cbf84873039af687dfab9be8b93aa6fa5 }

condition:
	$a0
}

        