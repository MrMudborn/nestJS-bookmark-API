import { Test } from '@nestjs/testing';
import { AppModule } from '../src/app.module';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { PrismaService } from '../src/prisma/prisma.service';
import * as pactum from 'pactum';
import { AuthDto } from 'src/auth/dto';
import { EditUserDto } from 'src/user/dto';
import { CreateBookmarkDto, EditBookmarkDto } from 'src/bookmark/dto';
import { inspect } from 'util';

describe('App e2e', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleRef.createNestApplication();
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
      }),
    );

    await app.init();
    await app.listen(3333);

    prisma = app.get(PrismaService);
    await prisma.cleanDB();
    pactum.request.setBaseUrl('http://localhost:3333');
  });

  afterAll(() => {
    app.close();
  });

  describe('Auth', () => {
    const dto: AuthDto = {
      email: 'pankajk@gmail.com',
      hash: '12345678',
    };

    describe('Signup', () => {
      it('Should throw an exception if the email empty', () => {
        return pactum
          .spec()
          .post('/auth/signup')
          .withBody({ ...dto, email: '' })
          .expectStatus(400);
      });
      it('Should throw an exception if the password empty', () => {
        return pactum
          .spec()
          .post('/auth/signup')
          .withBody({ ...dto, hash: '' })
          .expectStatus(400);
      });
      it('Should throw an exception if the fields are empty', () => {
        return pactum
          .spec()
          .post('/auth/signup')
          .withBody({ email: '', hash: '' })
          .expectStatus(400);
      });
      it('should create a new user', () => {
        return pactum
          .spec()
          .post('/auth/signup')
          .withBody(dto)
          .expectStatus(201);
      });
    });

    describe('Signin', () => {
      it('should throw an exception if the email is empty', () => {
        return pactum
          .spec()
          .post('/auth/signin')
          .withBody({ ...dto, email: '' })
          .expectStatus(400);
      });
      it('should throw an exception if the password is empty', () => {
        return pactum
          .spec()
          .post('/auth/signin')
          .withBody({ ...dto, hash: '' })
          .expectStatus(400);
      });
      it('should throw an exception if the fields are empty', () => {
        return pactum
          .spec()
          .post('/auth/signin')
          .withBody({ email: '', hash: '' })
          .expectStatus(400);
      });
      it('should return a token', () => {
        return pactum
          .spec()
          .post('/auth/signin')
          .withBody(dto)
          .expectStatus(200)
          .stores('userAt', 'access_token');
      });
    });
  });

  describe('Users', () => {
    describe('Get me', () => {
      it('Should current user', () => {
        return pactum
          .spec()
          .get('/users/me')
          .withHeaders({ Authorization: `Bearer $S{userAt}` })
          .expectStatus(200);
      });
    });

    describe('Edit user', () => {
      it('Should edit the user', () => {
        const dto: EditUserDto = {
          firstName: 'Pankaj',
          lastName: 'Kumar',
        };

        return pactum
          .spec()
          .get('/users/me')
          .withHeaders({ Authorization: `Bearer $S{userAt}` })
          .withBody(dto)
          .expectStatus(200);
      });
    });
  });

  describe('Bookmarks', () => {
    describe('Get empty bookmark', () => {
      it('Should get bookmark', () => {
        return pactum
          .spec()
          .get('/bookmark')
          .withHeaders({ Authorization: `Bearer $S{userAt}` })
          .expectStatus(200)
          .expectBody([]);
      });
    });

    describe('Create bookmark', () => {
      it('Should create bookmark', () => {
        const dto: CreateBookmarkDto = {
          link: 'https://nestjs.com/',
          title: 'NestJS',
          description:
            'NestJS is a framework for building efficient, scalable Node.js web applications.',
        };

        return pactum
          .spec()
          .post('/bookmark')
          .withHeaders({ Authorization: `Bearer $S{userAt}` })
          .withBody(dto)
          .expectStatus(201)
          .stores('bookmarkId', 'id');
      });
    });

    describe('Get bookmarks', () => {
      it('Should get bookmarks', () => {
        return pactum
          .spec()
          .get('/bookmark')
          .withHeaders({ Authorization: `Bearer $S{userAt}` })
          .expectStatus(200)
          .expectJsonLength(1);
      });
    });

    describe('Get bookmark by id', () => {
      it('Should get bookmark by id', () => {
        return pactum
          .spec()
          .get('/bookmark/{id}')
          .withPathParams('id', '$S{bookmarkId}')
          .withHeaders({ Authorization: `Bearer $S{userAt}` })
          .expectStatus(200);
      });
    });

    describe('Update bookmark by id', () => {
      it('Should edit bookmark', () => {
        const dto: EditBookmarkDto = {
          link: 'https://nestjs.com/',
          title: 'NestJS Tutorial',
          description:
            'NestJS is a framework for building efficient, scalable Node.js web applications.',
        };

        return pactum
          .spec()
          .patch('/bookmark/{id}')
          .withPathParams('id', '$S{bookmarkId}')
          .withHeaders({ Authorization: `Bearer $S{userAt}` })
          .withBody(dto)
          .expectStatus(200)
      });
    });

    describe('Delete bookmark', () => {
      it('Should get bookmark by id', () => {
        return pactum
          .spec()
          .delete('/bookmark/{id}')
          .withPathParams('id', '$S{bookmarkId}')
          .withHeaders({ Authorization: `Bearer $S{userAt}` })
          .expectStatus(204);
      });

      it('Should get empty bookmark', () => {
        return pactum
          .spec()
          .get('/bookmark')
          .withHeaders({ Authorization: `Bearer $S{userAt}` })
          .expectStatus(200)
          .expectJsonLength(0);
      });
    });
  });
});
