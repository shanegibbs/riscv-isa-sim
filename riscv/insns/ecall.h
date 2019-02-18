auto a7 = READ_REG(17);
if (a7 == 1) {
  auto a0 = READ_REG(10);
  fprintf(stderr, "%c", a0);
}
switch (STATE.prv)
{
  case PRV_U: throw trap_user_ecall();
  case PRV_S: throw trap_supervisor_ecall();
  case PRV_M: throw trap_machine_ecall();
  default: abort();
}
