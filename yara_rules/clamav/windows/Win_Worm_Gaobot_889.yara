rule Win_Worm_Gaobot_889
{
strings:
	$a0 = { 0b0f8b919cb329348713962ddba07c72695aea4ef7285a82c931fb105ad413742abf2d743dd7f95e4fb70fea5e94f02f0b33b73799c67b001f6712daf1189899780ee5385834371c7140efa9bae1a84c000c1d73bdf1b8a55c50d1aee4e5a6cd1e354bba775f276a5b6b1ed34cba6161a6cce02b123edc36c551a101dcdcea6b04d7efb9bf5bc0c39e3094bf15ebe9 }

condition:
	$a0
}

        