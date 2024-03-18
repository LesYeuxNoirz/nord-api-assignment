## Nord Security API Testing Assignment

### Usage
To run tests locally, follow the instructions below:
1. Clone the repo
2. Run `npm ci`
3. Provide the API key in the environment as `process.env.GO_REST_ACCESS_TOKEN` using any convenient method
4. Build JS code using `npm run build`
5. Run tests using `npm run test`

### CI
The repository has CI, please refer to the open test PR to see run results

_Note_: the CI workflow is triggered only for non-master branches

### Specific 3-rd party libs
- [email-validator](https://github.com/manishsaraan/email-validator) for email validation
- [xml2js](https://github.com/manishsaraan/email-validator) for xml to js conversion

### Notes
- The API key is provided in CI, to simply provide one locally, you can:
   - Add the key to the `test` command, so that it looks like this `GO_REST_ACCESS_TOKEN=YOUR_KEY node dist/test.js` if you're on a UNIX-compatible system
       or `export` the key first if you're on Windows
   - Explicitly do `process.env.GO_REST_ACCESS_TOKEN = your_key` at the top of the test file
- The XML format and old API versions are checked only once for GET because:
  - Testing them for each method would take a lot of space and time
  - I don't know whether those old versions are supported fully
- I'm not sure if I should've tested child endpoints like /id/posts. If I should've, I'd have tested
them in the same manner
- Plain SQL and script injections are ignored so there're no tests for them
- Please read comments, I comment on solutions and some bugs found there

change to trigger tests