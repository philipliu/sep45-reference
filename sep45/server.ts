import { Application, Router } from "jsr:@oak/oak";
import { challenge, ChallengeRequest, ChallengeResponse } from "./challenge.ts";

const router = new Router();

router
  .get("/challenge", async (context) => {
    const params = context.request.url.searchParams;
    const request: ChallengeRequest = Object.fromEntries(params) as ChallengeRequest;
    const response: ChallengeResponse = await challenge(request);
    context.response.body = response;
  });

const app = new Application();
app.use(router.routes());
app.use(router.allowedMethods());

app.listen({ port: 80 });
