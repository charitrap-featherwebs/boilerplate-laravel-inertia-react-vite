<?php

namespace App\Http\Controllers;

use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Laravel\Sanctum\PersonalAccessToken;

class AuthController extends Controller
{
    protected function createToken($user)
    {
        $token = $user->createToken('apiToken')->plainTextToken;

        $expiration = Carbon::now()->addYear();
        $accessToken = PersonalAccessToken::findToken($token);
        $accessToken->expires_at = $expiration;
        $accessToken->save();

        return $token;
    }

    public function register(Request $request)
    {
        $data = $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|unique:users,email',
            'password' => 'required|string|confirmed'
        ]);

        $user = User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => bcrypt($data['password'])
        ]);

        $token = $this->createToken($user);

        $res = [
            'user' => $user,
            'token' => $token
        ];
        return response($res, 201);
    }

    public function login(Request $request)
    {
        $data = $request->validate([
            'email' => 'required|string',
            'password' => 'required|string'
        ]);

        $user = User::where('email', $data['email'])->first();

        if (!$user || !Hash::check($data['password'], $user->password)) {
            return response([
                'msg' => 'incorrect username or password'
            ], 401);
        }

        $token = $this->createToken($user);

        $res = [
            'user' => $user,
            'token' => $token
        ];

        return response($res, 201);
    }

    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();
        return [
            'message' => 'user logged out'
        ];
    }

    public function logoutOtherDevices(Request $request)
    {
        $request->user()->tokens()->where('id', '!=', $request->user()->currentAccessToken()->id)->delete();
        return [
            'message' => 'user logged out from other devices'
        ];
    }

    public function logoutAllDevices(Request $request)
    {
        $request()->user()->tokens()->delete();
        return [
            'message' => 'user logged out from all devices'
        ];
    }

}
