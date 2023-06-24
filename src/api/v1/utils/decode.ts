import bcrypt from 'bcrypt';
export const decode = async (password: string, hash: string) => {
  const salt = await bcrypt.genSalt(10);
  return await bcrypt.compare(password, hash).then((res) => res == true);
};
