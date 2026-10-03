import {readFileSync} from 'node:fs';
import {runInNewContext} from 'node:vm';
import {describe,it,expect} from 'vitest';
const source=readFileSync(new URL('../../jstu_passkey/static/oauth_authorize.js',import.meta.url),'utf8');
function classify(error:unknown){
 const status={hidden:true,textContent:'',className:'',dataset:{}};
 return runInNewContext(source+'\noauthErrorCode(input)',{input:error,DOMException,TypeError,URL,document:{querySelector:(selector:string)=>selector==='#oauth-status'?status:{addEventListener(){},dataset:{}}},window:{isSecureContext:false,clearTimeout(){},setTimeout(){return 0;}}});
}
describe('OAuth browser error handoff',()=>{
 it('distinguishes cancellation, policy closure, provider and network failures',()=>{
  expect(classify(new DOMException('cancelled','NotAllowedError'))).toBe('access_denied');
  expect(classify({code:'registration_not_allowed',status:403})).toBe('registration_not_allowed');
  expect(classify({status:503})).toBe('server_error');
  expect(classify(new TypeError('Failed to fetch'))).toBe('temporarily_unavailable');
  expect(classify({status:400})).toBe('authentication_failed');
 });
});
