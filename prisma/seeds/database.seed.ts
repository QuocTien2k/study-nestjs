import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
  const saltRounds = 10;

  const passwordAdmin = await bcrypt.hash('123456', saltRounds);
  const passwordUser = await bcrypt.hash('123456', saltRounds);

  await prisma.user.createMany({
    data: [
      {
        email: 'admin@gmail.com',
        password: passwordAdmin,
        name: 'Admin',
      },
      {
        email: 'user1@gmail.com',
        password: passwordUser,
        name: 'User One',
      },
    ],
    skipDuplicates: true, // tránh lỗi unique email
  });

  console.log('Seed users with hashed passwords successfully');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
