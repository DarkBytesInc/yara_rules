rule Win_Downloader_Small_3252
{
strings:
	$a0 = { 6a66425cdcc091578a2efbdc4e0bff007d03d769a70eb7f3cc71f11126d3732320ea8e797d8dc8377208a05d6c3758acea8001c3a2c7d679d45b9860a39c97d286db82c4c37d80b4ba5256609da36d13bc7e8a7a90c5ff684b4415ab13bf7ec8be6450c040be0b0dc21a36ecd6 }

condition:
	$a0
}

        