rule Win_Trojan_VB_1207
{
strings:
	$a0 = { ff2d00054bffff0200800c000ba30004003174ff00186c74ff765b000ba30004002370fffb302f70ff1c39000008765c004378ff1e500200186c74ff765d000ba30004002370fffb302f70ff1c5c000008765e004378ff1e500200186c74ff765f000ba30004002370fffb302f70ff1c7f0000087660004378ff1e500200186c74ff7661000ba30004002370fffb302f70ff }

condition:
	$a0
}

        