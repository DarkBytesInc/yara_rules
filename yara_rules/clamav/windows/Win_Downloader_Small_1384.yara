rule Win_Downloader_Small_1384
{
strings:
	$a0 = { 496e74623affc35c706c6f7cae3e5c69d20a362e106085017075720a6c6d6f6ea1656b68ae577c69dfaa9463ec03524c446f77e26ca7ae548aa1c8878e737959f46d5e65c768 }

condition:
	$a0
}

        
