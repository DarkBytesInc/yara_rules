rule Win_Downloader_Zdesnado_4
{
strings:
	$a0 = { 6890787a93ce83c3c7029e050481fb34c27ca9ff358868d92d80e828001a9b59bb0350b1085ee06a01687c340575e225538ccfccb2cc50963efb0c1c88accc861ee0ccd60a6f3fedcfb31ea853a83a26e178faa8b3ea7884a7db113e8468cc99655b878738e4f5cce359c82bc72856d9f218006242d5af68581fcda7a300027ddfeaeec543bf1c01f8cbaccb }

condition:
	$a0
}

        