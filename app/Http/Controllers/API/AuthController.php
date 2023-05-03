<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        return response()->json([
            'user' => $user,
        ]);
    }

    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        // if (!$token = Auth::guard('api')->attempt($credentials)) {
        if (!$token = JWTAuth::attempt($credentials)) {
            return response()->json(['error' => 'Login failed for given credentials'], 401);
        }

        $user = JWTAuth::user();
        $refreshToken = JWTAuth::fromUser($user, ['token_type' => 'refresh']);

        return response()->json([
            'user' => $user,
            'token' => $token,
            'refresh_token' => $refreshToken,
        ]);
    }

    public function refresh(Request $request)
    {
        // Get the current refresh token from the request
        $refreshToken = $request->input('refresh_token');

        // Attempt to refresh the token
        $token = JWTAuth::refresh($refreshToken);

        // Return the new access token to the client
        return response()->json([
            'token' => $token,
        ]);
    }
}
