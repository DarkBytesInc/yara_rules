rule Win_Downloader_Small_271
{
strings:
	$a0 = { 756e6761636874756e672e636f6d2f30303231223b0a0a77696e646f772e6f70656e28226a6176617363726970743a5c223c534352495054205352433d27222b626173655f706174682b222f536372697074426f64794a73702e706870273e3c5c2f5343524950543e5c }

condition:
	$a0
}

        