rule Win_Downloader_Zlob_1518
{
strings:
	$a0 = { 6a251d81c1b2a9125ea0903b5400c673da9872da5e60b2e9cde97556c8f7533be79ed26eb84d7361b296de70982e28d6fe3f8bba019f76b8c8e53d9409bc295b6df199935a780d7c5aec1b840e5e36ed0daaff1729ae6ab5ee5566e8b6b1b44fafbe526468ad }

condition:
	$a0
}

        
