rule Win_Downloader_Small_2477
{
strings:
	$a0 = { 8a7b4224c3b0b8252c809e220ffb71cdb74894c109b7b3fed25195916bb6ed7326d4d8723a848fb446414f4f2ccfc9462cc3ac492cd6cd0eb4c811fc4cf6d16d58adfe6e24dadc6f2bfbd46f2cf64026b638ad523bd6cf753cc7f46f2dd8f06e2bc2d1640f00ddda9e }

condition:
	$a0
}

        
