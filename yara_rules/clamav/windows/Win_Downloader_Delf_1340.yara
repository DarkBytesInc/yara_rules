rule Win_Downloader_Delf_1340
{
strings:
	$a0 = { c014902280828c8f8fa0808402273c921c60dddeb5b77f16f73bdca7e1bf80eee677205bddc81b6eef01b77205b57916eac17b5bc905a4805d7202db901bae701b5c82dae482db9c171b9202b901bdb901edee4177b72036ee0377bb82b6f72ddee77bffffffb7dff7f7f7cf9cf3efdf9f7cf9f7efde739fb7f7bff045cc902698c366b359779b0efa4487ca }

condition:
	$a0
}

        