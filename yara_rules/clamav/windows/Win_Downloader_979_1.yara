rule Win_Downloader_979_1
{
strings:
	$a0 = { 8a999ab513fc5e98e08c71177317bce57bad45bc7f08bf6b7dd3b5cee5c15d8304b669e8c7d30c161123b593bfd8426ccfc8d4b51f2fef6c0e6f214ad92e8c5eb2d1d6a017b926ed661b18157078e06f0430acc65498693e1736b2ea }

condition:
	$a0
}

        
