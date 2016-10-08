BEGIN {
  sum = 0;
  cnt = 0;
  max = 0;
  min = 999999;
}

{
  if ($NF ~ /[0-9]+/) {
    val = int($NF);
    sum += $NF;
    cnt += 1;
    if (max < val) {
      max = val;
    }
    if (min > val) {
      min = val;
    }
    printf("max %d min %d avg %f \r\n", max, min, sum/cnt);
  }
}

END {
  printf("max %d min %d avg %f \r\n", max, min, sum/cnt);
}
