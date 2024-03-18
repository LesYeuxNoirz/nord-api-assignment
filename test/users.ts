import request from 'supertest';
import { describe } from 'mocha';
import { expect } from 'chai';
import { validate } from 'email-validator';

describe('Users', () => {
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

  const requester = request('https://gorest.co.in/public/v2/users');

  it('should return a valid list list of first 10 users on a GET request', async () => {
    const response = await requester.get('/');
    expect(response.status).to.eq(200);
    const users = response.body as User[];
    expect(users.length).to.eq(10);

    users.forEach(user => {
      expect(user.id).to.be.a('number');
      expect(user.name).to.match(/^[a-z\s.]+$/i);
      // We could either copy-paste a very long RegExp or use an existing implementation. Since this would be a testing
      // (dev) dependency in a real project, we should be fine using a ready-made implementation
      expect(validate(user.email)).to.be.true;
      expect(user.gender).to.be.oneOf(Object.values(UserGender));
      expect(user.status).to.be.oneOf(Object.values(UserStatus));
    });
  });

  it('should return a 404 and a not-found message when querying for a non-existing user', async () => {
    const response = await requester.get('/-1');
    expect(response.status).to.eq(404);
    expect(response.body).to.have.property('message', 'Resource not found');
  });
});
