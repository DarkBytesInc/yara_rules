rule Win_Spyware_Banker_2619
{
strings:
	$a0 = { b1749c8462ed5f5c5161076e7b1d6079311b5222edb674f79bd135dd5c5e4a12516c50c3f3670dac064ac70f8878663167474147314879594d37b879632af864be31e4449bf115e65ddb460d518b5a747c7306d7c5254e96ea3f17f489b5d978542a23403c6eade47dd8e00019fd3009992fa7c8e19339822e32b7 }

condition:
	$a0
}

        