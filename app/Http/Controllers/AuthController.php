<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Http\Requests\LoginRequest;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Crypt;
use App\Http\Requests\RegisterRequest;
use Illuminate\Support\Facades\Artisan;

class AuthController extends Controller
{
    //register function using JWT
    public function register(RegisterRequest $request)
    {
        DB::beginTransaction();
        try {
            $user = User::create(array_merge(
                $request->all(),
                ['password' => Hash::make($request->password)]
            ));

            if (!$token = auth()->attempt(['email' => $user->email, 'password' => 'password'])) {
                return response()->json(['error' => 'Unauthorized'], 401);
            }

            return $this->respondWithToken($token);

            //commit changes
            DB::commit();
        } catch (\Exception $e) {
            //rollback data
            DB::rollBack();

            dd($e->getMessage());
        }

    }

    //login function using JWT
    public function login(LoginRequest $request)
    {
        try {
            $credentials = $request->only('email', 'password');

            if (!$token = auth()->attempt($credentials)) {
                return response()->json(['error' => 'Unauthorized'], 401);
            }

            return $this->respondWithToken($token);
        } catch (\Exception $e) {
            dd($e->getMessage());
        }
    }

    //refresh token to existing token of current auth user
    public function refreshToken()
    {
        try {
            if (!Auth::check()) {
                return response()->json(['message' => 'Unauthenticated'], 401);
            }

            $user = Auth::user();

            $token = JWTAuth::fromUser($user);

            return $this->respondWithToken($token);
        } catch (\Exception $e) {
            return response()->json(['message' => 'Failed to refresh token'], 500);
        }
    }

    //encrypt the data resource as jwt token
    public function encryptedToken(Request $request)
    {
        try {
            $payload = [
                'message' => 'hello world',
            ];

            $encryptedPayload = Crypt::encryptString(json_encode($payload));

            $customClaims = ['payload' => $encryptedPayload];

            $token = JWTAuth::claims($customClaims)->fromUser(Auth::user());

            return $this->respondWithToken($token);

        } catch (\Exception $e) {

            return response()->json(['error' => 'Internal Server Error'], 500);

        }
    }

    //decrypt the data resource from jwt token
    public function decryptedToken(Request $request)
    {
            $token = $request->bearerToken();

            $payload = JWTAuth::parseToken($token)->getPayload();

            $encryptedPayload = $payload->get('payload');

            $decryptedPayload = Crypt::decryptString($encryptedPayload);

            return response()->json(['decrypted_payload' => json_decode($decryptedPayload, true)]);
    }

    //revoke or delete the current auth user's token 
    public function revokeToken(Request $request)
    {
        try {

            JWTAuth::invalidate(JWTAuth::getToken());

            return response()->json(['message' => 'Token revoked successfully']);

        } catch (\Exception $e) {
            return response()->json(['error' => 'Internal Server Error'], 500);
        }
    }

      /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => $tokenTTL = config('jwt.ttl') * 60
        ]);
    }
}
