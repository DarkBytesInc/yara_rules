rule Win_Downloader_Small_1618
{
strings:
	$a0 = { c055687134141364ff30648920ff056456141333c05a59596489106878341413c3e932f5ffffebf85dc38bc0832d6456141301c3ff257c6114138bc0ff25746114138bc0ff25706114138bc0ff256c6114138bc0ff25686114138bc0ff25646114138bc0687474703a2f2f7777772e }

condition:
	$a0
}

        