rule Win_Worm_Bobax_21
{
strings:
	$a0 = { 7d353b696a934bf6b1623ed9dbbf475c94dc9b677bfdae73835a2c4a30a223399a502e4ae6cae00350c25136676b6f5c8ba97980e048785c539760595eeb2347c32897548dc67991fdb94f492acbc215018994d76e837100f74774acdc7b496cf77c667edcafee4d5dd7577f32d437c37b00887e3cf560dbd72d44bbee506024a629 }

condition:
	$a0
}

        