rule Win_Dropper_Delf_663
{
strings:
	$a0 = { bd13bd15bb131313539e566b4312460b9e239ca663bd1380567b439e5677439e5667434912460f9e566343124673bd578058ef4312461bbd038058ff4312461bda58ef57131313da583b14131313b9da583f18138058ff438058ef43bd13bd13bd13bd13bd13bd139e566b43bd131246179e58ff43124673bd131246073e1d936e13a818bd13124607b14e9e38b0d51713805313 }

condition:
	$a0
}

        