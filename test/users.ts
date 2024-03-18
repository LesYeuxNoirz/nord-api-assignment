import request, { Response } from 'supertest';
import { describe } from 'mocha';
import { expect } from 'chai';
import { validate } from 'email-validator';
import { Parser } from 'xml2js';
import { randomUUID } from 'crypto';

process.env.GO_REST_ACCESS_TOKEN =
  'd7c60efb5994ac6f6160116c0ebed2446804f2e5cff5e671b4bd5481dd125cd9';

describe('Users', function () {
  // We use the function() syntax to get access to the proper this and increase the timeout as the API is not that fast)
  this.timeout(3000);

  enum UserGender {
    MALE = 'male',
    FEMALE = 'female'
  }

  enum UserStatus {
    ACTIVE = 'active',
    INACTIVE = 'inactive'
  }

  interface User {
    id: string;
    name: string;
    email: string;
    gender: UserGender;
    status: UserStatus;
  }

  interface ValidatedField {
    field: string;
    message: string;
  }

  const DEFAULT_USERS_PER_PAGE = 10;
  const BASE_API_URL = 'https://gorest.co.in';
  const v2APIUrl = `${BASE_API_URL}/public/v2/users`;
  const requester = request(v2APIUrl);

  // @ts-ignore
  const makeAuthorizedRequest = (
    req: ReturnType<typeof requester.get>,
    token = process.env.GO_REST_ACCESS_TOKEN
  ) => {
    return req.set('Authorization', `Bearer ${token}`);
  };

  const validateUser = (user: User, expectedValues: Partial<User> = {}) => {
    expect(user.id).to.be.a('number');
    const { gender, email, name, status } = expectedValues;

    if (name) {
      expect(user.name).to.eq(name);
    } else {
      expect(user.name).to.match(/^[a-z\s.]+$/i);
    }

    if (email) {
      expect(user.email).to.eq(email);
    } else {
      // We could either copy-paste a very long RegExp or use an existing implementation. Since this would be a testing
      // (dev) dependency in a real project, we should be fine using a ready-made implementation
      expect(validate(user.email)).to.be.true;
    }

    expect(user.gender).to.be.oneOf(
      (gender && [gender]) ?? Object.values(UserGender)
    );

    expect(user.status).to.be.oneOf(
      (status && [status]) ?? Object.values(UserStatus)
    );
  };

  const getUsers = (query?: Partial<User>) => {
    let url = '/';

    if (query) {
      url = '?';

      Object.entries(query).forEach(([key, value]) => {
        url += `${key}=${value}`;
      });
    }

    return requester.get(url).then(r => r.body as User[]);
  };

  const getCantBeBlankMessage = (key: keyof User) => {
    let message = "can't be blank";

    if (key === 'gender') {
      // There's a typo in the server response
      message += ', can be male of female';
    }

    return message;
  };

  const getUser = (): Partial<User> => {
    return {
      name: 'Mykola Iskorostenskyi',
      email: `${randomUUID()}@gmail.com`,
      gender: UserGender.MALE,
      status: UserStatus.ACTIVE
    };
  };

  const setUpUnexpectedValueChecks = (
    getReq: () => ReturnType<typeof requester.get>
  ) => {
    (['gender', 'status'] as Array<keyof User>).forEach(key => {
      it(`should not accept an unexpected value for the ${key} field`, async () => {
        const user = getUser();
        // The field is restricted to UserGender but we need an invalid value here
        // @ts-ignore
        user[key] = 'test';

        const response = await makeAuthorizedRequest(getReq()).send(user);
        expect(response.status).to.eq(422);
        const body = response.body[0] as ValidatedField;
        expect(body.field).to.eq(key);
        expect(body.message).to.eq(getCantBeBlankMessage(key));
      });
    });
  };

  context(HttpMethod.GET, () => {
    it('should return a valid list list of first 10 users on a GET request', async () => {
      const response = await requester.get('/');
      expect(response.status).to.eq(200);
      const users = response.body as User[];
      expect(users.length).to.eq(DEFAULT_USERS_PER_PAGE);
      users.forEach(user => validateUser(user));
    });

    it('should return the user with the matching id', async () => {
      const firstPageUsers = await getUsers();

      const user = (await requester
        .get(`/${firstPageUsers[0].id}`)
        .then(r => r.body)) as User;

      expect(user).to.deep.eq(firstPageUsers[0]);
    });

    it('should allow to query more than the default 10 users per page', async () => {
      const users = (await requester
        .get('?per_page=20')
        .then(r => r.body)) as User[];

      // I wanted to check the X-Pagination-Limit header here as well but it keeps the value 10 regardless of the query parameter value
      expect(users.length).to.eq(20);
    });

    it('should now allow to query more than 100 users per page', async () => {
      const users = (await requester
        .get('?per_page=101')
        .then(r => r.body)) as User[];

      // Wierd behavior here, it doesn't return 100 users if you request more, it just always returns 10
      expect(users).to.have.length(10);
    });

    it('should allow to query users from another page', async () => {
      const PAGE_NUMBER = 2;

      const pageOneUsers = await getUsers();
      const secondPageResponse = await requester.get(`?page=${PAGE_NUMBER}`);

      expect(secondPageResponse.headers['x-pagination-page']).to.eq(
        PAGE_NUMBER.toString()
      );

      const secondPageUsers = secondPageResponse.body as User[];
      expect(pageOneUsers).not.to.deep.eq(secondPageUsers);
    });

    it('should return an empty array when querying a page above the total page number', async () => {
      const response = await requester.get('/');
      const totalPageCount = response.header['x-pagination-pages'];

      const users = (await requester
        .get(`?page=${totalPageCount + 1}`)
        .then(r => r.body)) as User[];

      expect(users).to.be.an('array');
      expect(users).to.have.length(0);
    });

    it('should return a 404 and a not-found message when querying for a non-existing user', async () => {
      const response = await requester.get('/-1');
      expect(response.status).to.eq(404);
      expect(response.body).to.have.property('message', 'Resource not found');
    });

    it('should be able return the response in the xml format', async () => {
      const jsonResponse = await getUsers();

      const xmlResponse = await request(`${v2APIUrl}.xml`)
        .get('/')
        .then(r => r.text);

      const parser = new Parser({ explicitArray: false });

      const parsedXml = (
        (await parser.parseStringPromise(xmlResponse)) as {
          objects: { object: Array<User & { id: { _: string } }> };
        }
      ).objects.object;

      expect(jsonResponse).to.have.length(parsedXml.length);

      for (let i = 0; i < jsonResponse.length; i++) {
        const jsonResponseUser = jsonResponse[i];
        const parsedXmlUser = parsedXml[i];

        expect(Number.parseInt(parsedXmlUser.id._, 10)).to.eq(
          jsonResponseUser.id
        );

        expect(parsedXmlUser.name).to.eq(jsonResponseUser.name);
        expect(parsedXmlUser.email).to.eq(jsonResponseUser.email);
        expect(parsedXmlUser.gender).to.eq(jsonResponseUser.gender);
        expect(parsedXmlUser.status).to.eq(jsonResponseUser.status);
      }
    });

    context('Older API versions', () => {
      ['public-api', 'public/v1'].forEach(apiPath => {
        it(`should allow to retrieve users using the "${apiPath}" API path`, async () => {
          const url = `${BASE_API_URL}/${apiPath}/users`;

          const body = (await request(url)
            .get('/')
            .then(r => r.body)) as {
            meta: {
              pagination: {
                total: number;
                pages: number;
                page: number;
                limit: number;
                links: object;
              };
            };
            data: User[];
            code?: number;
          };

          const isV1 = apiPath.includes('v1');

          const { pages, page, limit, total, links } = body.meta.pagination;
          expect(pages).to.be.a('number');
          expect(page).to.eq(1);
          expect(limit).to.eq(DEFAULT_USERS_PER_PAGE);
          expect(total).to.be.a('number');

          if (isV1) {
            const { previous, next, current } = links as {
              previous: null;
              current: string;
              next: string;
            };

            expect(previous).to.be.null;
            expect(current).to.eq(`${url}?page=1`);
            expect(next).to.eq(`${url}?page=2`);
          } else {
            expect(links).to.be.undefined;
          }

          body.data.forEach(user => validateUser(user));
          expect(body.code).to.eq(isV1 ? undefined : 200);
        });
      });
    });

    context('Search', () => {
      // Sample user taken from the 20th page
      Object.entries({
        id: 6771826,
        name: 'Brijesh Bandopadhyay DO',
        email: 'bandopadhyay_do_brijesh@murray-mills.test',
        gender: 'female',
        status: 'inactive'
      }).forEach(([key, value]) => {
        it(`should allow searching users by their ${key}`, async () => {
          const users = await getUsers({ [key]: value });

          users.forEach(user => {
            // Get rid of TS errors, we're sure this is a key of User
            expect(user[key as keyof User]).to.eq(value);
          });
        });
      });
    });
  });

  const enum HttpMethod {
    GET = 'GET',
    POST = 'POST',
    PUT = 'PUT',
    PATCH = 'PATCH',
    DELETE = 'DELETE'
  }

  const setUpUnauthorizedRequestChecks = async (
    httpMethod: Exclude<HttpMethod, HttpMethod.GET>
  ) => {
    ['without a token', 'with an invalid token'].forEach(condition => {
      it(`should not allow interactions with the API using the ${httpMethod} method ${condition}`, async () => {
        const firstUser = await getUsers().then(users => users[0]);
        const reqUrl = `/${firstUser.id}`;
        let reqPromise: ReturnType<typeof requester.get>;

        switch (httpMethod) {
          case HttpMethod.POST:
            reqPromise = requester.post(reqUrl);
            break;
          case HttpMethod.PUT:
            reqPromise = requester.put(reqUrl);
            break;
          case HttpMethod.PATCH:
            reqPromise = requester.patch(reqUrl);
            break;
          default:
            reqPromise = requester.delete(reqUrl);
        }

        const isInvalidTokenCondition = condition.includes('invalid');
        let response: Response;

        if (isInvalidTokenCondition) {
          response = await makeAuthorizedRequest(reqPromise, 'test');
        } else {
          response = await reqPromise;
        }

        // Behavior for the POST request is different from other ones
        if (httpMethod === HttpMethod.POST) {
          expect(response.status).to.eq(404);
          expect(response.headers['content-type']).to.include('text/html');
          expect(response.text).to.include('Not Found');
        } else {
          expect(response.status).to.eq(401);
          expect(response.headers['content-type']).to.include(
            'application/json'
          );
          expect(response.body).to.have.property(
            'message',
            isInvalidTokenCondition ? 'Invalid token' : 'Authentication failed'
          );
        }
      });
    });
  };

  context(HttpMethod.POST, () => {
    // Since this test requires registration before trying to sign up a new user with the same email, it also covers
    // the basic registration case
    it('should not allow to create a user with an already taken email', async () => {
      const user = getUser();

      const responseUser = (await makeAuthorizedRequest(requester.post('/'))
        .send(user)
        .then(r => r.body)) as User;

      validateUser(responseUser, user);

      const existingResponse = await makeAuthorizedRequest(
        requester.post('/')
      ).send(user);

      expect(existingResponse.status).to.eq(422);
      const existingResponseBody = existingResponse.body[0] as ValidatedField;
      expect(existingResponseBody.field).to.eq('email');
      expect(existingResponseBody.message).to.eq('has already been taken');
    });

    const emptyFieldsUser = getUser();

    Object.keys(emptyFieldsUser).forEach(key => {
      it(`should not allow to create a new user with an empty ${key}`, async () => {
        const user = { ...emptyFieldsUser };
        // There're many ways to deal with this TS error but since it's a stupid one, we'll just ignore it
        // @ts-ignore
        delete user[key];

        const body = await makeAuthorizedRequest(requester.post('/'))
          .send(user)
          .then(r => r.body[0] as ValidatedField);

        expect(body.field).to.eq(key);
        expect(body.message).to.eq(getCantBeBlankMessage(key as keyof User));
      });
    });

    setUpUnexpectedValueChecks(() => requester.post('/'));
    setUpUnauthorizedRequestChecks(HttpMethod.POST);
  });

  // The setUpUnauthorizedRequestChecks doesn't accept HttpMethod.GET but TS always the type of non-object arrays as
  // a primitive type, that's why we need to force it to consider it a readonly array instead
  (
    [
      {
        httpMethod: HttpMethod.PUT,
        makeRequest: requester.put
      },
      {
        httpMethod: HttpMethod.PATCH,
        makeRequest: requester.patch
      }
    ] as const
  ).forEach(({ httpMethod, makeRequest }) => {
    context(httpMethod, () => {
      let newUser: User;

      beforeEach(async () => {
        newUser = (await makeAuthorizedRequest(requester.post('/'))
          .send(getUser())
          .then(r => r.body)) as User;
      });

      it("should not allow to update an existing user's id", async () => {
        const user = await makeAuthorizedRequest(makeRequest(`/${newUser.id}`))
          .send({ id: 123 })
          .then(r => r.body as User);

        expect(user).to.deep.eq(newUser);
      });

      const keys: Array<{ key: keyof User; value: User[keyof User] }> = [
        {
          key: 'name',
          value: 'Jane Doe'
        },
        {
          key: 'email',
          value: `${randomUUID()}@gmail.com`
        },
        {
          key: 'gender',
          value: UserGender.FEMALE
        },
        {
          key: 'status',
          value: UserStatus.INACTIVE
        }
      ];

      keys.forEach(({ key, value }) => {
        it(`should allow to update an existing user\'s ${key} with a valid value`, async () => {
          const response = await makeAuthorizedRequest(
            makeRequest(`/${newUser.id}`)
          ).send({ [key]: value });

          const updatedUser = { ...newUser, [key]: value };
          expect(response.status).to.eq(200);
          expect(response.body).to.deep.eq(updatedUser);
        });
      });

      it('should return a 404 and a not-found message when trying to update a non-existing user', async () => {
        const response = await makeAuthorizedRequest(makeRequest('/-1'));
        expect(response.status).to.eq(404);
        expect(response.body).to.have.property('message', 'Resource not found');
      });

      setUpUnexpectedValueChecks(() =>
        makeAuthorizedRequest(makeRequest(`/${newUser.id}`))
      );

      setUpUnauthorizedRequestChecks(httpMethod);
    });
  });

  context(HttpMethod.DELETE, () => {
    it('should allow to delete an existing user', async () => {
      const newUser = (await makeAuthorizedRequest(requester.post('/'))
        .send(getUser())
        .then(r => r.body)) as User;

      const deleteResponse = await makeAuthorizedRequest(
        requester.delete(`/${newUser.id}`)
      );

      expect(deleteResponse.status).to.eq(204);

      const matchingUsers = await getUsers({ id: newUser.id });
      expect(matchingUsers).to.have.length(0);
    });

    it('should return a 404 and a not-found message when trying to delete a non-existing user', async () => {
      const response = await makeAuthorizedRequest(requester.delete(`/-1`));
      expect(response.status).to.eq(404);
      expect(response.body).to.have.property('message', 'Resource not found');
    });

    setUpUnauthorizedRequestChecks(HttpMethod.DELETE);
  });
});
