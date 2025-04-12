<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use Illuminate\Support\Facades\Log;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);
    
        $user = User::where('email', $request->email)->first();
    
        if (! $user || ! Hash::check($request->password, $user->password)) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }

        // Create token with role-based abilities
        $token = $user->createToken('auth_token', [$user->role])->plainTextToken;
    
        return response()->json([
            'token' => $token,  
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'birthdate' => $user->birthdate,
                'role' => $user->role,
            ]
        ]);
    }

    public function register(Request $request)
    {
        $validated = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8|confirmed',
            'birthdate' => 'required|date|', 
        ]);
    
        try {
            $user = User::create([
                'name' => $validated['name'],
                'email' => $validated['email'],
                'password' => Hash::make($validated['password']),
                'birthdate' => $validated['birthdate'], 
                'role' => 'user',
            ]);
    
            $token = $user->createToken('auth_token', ['user'])->plainTextToken;
    
            return response()->json([
                'token' => $token,
                'user' => [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                    'birthdate' => $user->birthdate, 
                    'role' => $user->role,
                ]
            ], 201);
    
        } catch (\Exception $e) {
            Log::error('Registration failed: ' . $e->getMessage());
            return response()->json([
                'message' => 'Registration failed. Please try again.'
            ], 500);
        }
    }

    public function logout(Request $request)
    {
        try {
            $request->user()->currentAccessToken()->delete();
            return response()->json([
                'message' => 'Logged out successfully'
            ]);
        } catch (\Exception $e) {
            Log::error('Logout error: ' . $e->getMessage());
            return response()->json([
                'message' => 'Logout failed'
            ], 500);
        }
    }

    public function user(Request $request)
    {
        return response()->json([
            'id' => $request->user()->id,
            'name' => $request->user()->name,
            'email' => $request->user()->email,
            'birthdate' => $request->user()->birthdate,
            'role' => $request->user()->role,
        ]);
    }
}
