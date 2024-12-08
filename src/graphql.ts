import { GraphQLResolveInfo, GraphQLScalarType, GraphQLScalarTypeConfig } from 'graphql';
export type Maybe<T> = T | null;
export type InputMaybe<T> = Maybe<T>;
export type Exact<T extends { [key: string]: unknown }> = { [K in keyof T]: T[K] };
export type MakeOptional<T, K extends keyof T> = Omit<T, K> & { [SubKey in K]?: Maybe<T[SubKey]> };
export type MakeMaybe<T, K extends keyof T> = Omit<T, K> & { [SubKey in K]: Maybe<T[SubKey]> };
export type MakeEmpty<T extends { [key: string]: unknown }, K extends keyof T> = { [_ in K]?: never };
export type Incremental<T> = T | { [P in keyof T]?: P extends ' $fragmentName' | '__typename' ? T[P] : never };
export type RequireFields<T, K extends keyof T> = Omit<T, K> & { [P in K]-?: NonNullable<T[P]> };
/** All built-in and custom scalars, mapped to their actual values */
export type Scalars = {
  ID: { input: string; output: string; }
  String: { input: string; output: string; }
  Boolean: { input: boolean; output: boolean; }
  Int: { input: number; output: number; }
  Float: { input: number; output: number; }
  DateTime: { input: any; output: any; }
};

export type LoginResponse = {
  __typename?: 'LoginResponse';
  accessToken: Scalars['String']['output'];
  message: Scalars['String']['output'];
  refreshToken: Scalars['String']['output'];
};

export type Mutation = {
  __typename?: 'Mutation';
  deleteProfile: User;
  deleteUserById: User;
  loginUser: LoginResponse;
  refreshToken: RefreshResponse;
  registerUser: RegisterResponse;
  resetPwdConf: LoginResponse;
  resetPwdSent: ResetResponse;
  updateProfile: User;
  updateUserById: User;
  verifyRegister: LoginResponse;
};


export type MutationDeleteUserByIdArgs = {
  id: Scalars['Int']['input'];
};


export type MutationLoginUserArgs = {
  loginUserInput: LoginUserInput;
};


export type MutationRefreshTokenArgs = {
  refreshToken: RefreshTokenInput;
};


export type MutationRegisterUserArgs = {
  registerUserInput: RegisterUserInput;
};


export type MutationResetPwdConfArgs = {
  resetPwdConfInput: ResetPwdConfInput;
};


export type MutationResetPwdSentArgs = {
  resetPwdSentInput: ResetPwdSentInput;
};


export type MutationUpdateProfileArgs = {
  updateProfileInput: UpdateProfileInput;
};


export type MutationUpdateUserByIdArgs = {
  updateUserInput: UpdateUserInput;
};


export type MutationVerifyRegisterArgs = {
  verificationToken: Scalars['String']['input'];
};

export type Query = {
  __typename?: 'Query';
  getAllUsers: Array<User>;
  getProfile: User;
  getUserById: User;
};


export type QueryGetUserByIdArgs = {
  id: Scalars['Int']['input'];
};

export type RefreshResponse = {
  __typename?: 'RefreshResponse';
  accessToken: Scalars['String']['output'];
  message: Scalars['String']['output'];
  refreshToken: Scalars['String']['output'];
};

export type RegisterResponse = {
  __typename?: 'RegisterResponse';
  message: Scalars['String']['output'];
  verificationToken: Scalars['String']['output'];
};

export type ResetResponse = {
  __typename?: 'ResetResponse';
  message: Scalars['String']['output'];
  resetToken: Scalars['String']['output'];
};

export type UpdateProfileInput = {
  firstName?: InputMaybe<Scalars['String']['input']>;
  lastName?: InputMaybe<Scalars['String']['input']>;
  password?: InputMaybe<Scalars['String']['input']>;
  whatsapp?: InputMaybe<Scalars['String']['input']>;
};

export type UpdateUserInput = {
  firstName?: InputMaybe<Scalars['String']['input']>;
  id: Scalars['Int']['input'];
  lastName?: InputMaybe<Scalars['String']['input']>;
  password?: InputMaybe<Scalars['String']['input']>;
  whatsapp?: InputMaybe<Scalars['String']['input']>;
};

export type User = {
  __typename?: 'User';
  createdAt: Scalars['DateTime']['output'];
  email: Scalars['String']['output'];
  firstName: Scalars['String']['output'];
  id: Scalars['Int']['output'];
  lastName: Scalars['String']['output'];
  role: Scalars['String']['output'];
  updatedAt: Scalars['DateTime']['output'];
  verified: Scalars['Boolean']['output'];
  whatsapp?: Maybe<Scalars['String']['output']>;
};

export type LoginUserInput = {
  email: Scalars['String']['input'];
  password: Scalars['String']['input'];
};

export type RefreshTokenInput = {
  refreshToken: Scalars['String']['input'];
};

export type RegisterUserInput = {
  email: Scalars['String']['input'];
  firstName: Scalars['String']['input'];
  lastName: Scalars['String']['input'];
  password: Scalars['String']['input'];
  whatsapp: Scalars['String']['input'];
};

export type ResetPwdConfInput = {
  newPassword: Scalars['String']['input'];
  resetToken: Scalars['String']['input'];
};

export type ResetPwdSentInput = {
  email: Scalars['String']['input'];
};



export type ResolverTypeWrapper<T> = Promise<T> | T;


export type ResolverWithResolve<TResult, TParent, TContext, TArgs> = {
  resolve: ResolverFn<TResult, TParent, TContext, TArgs>;
};
export type Resolver<TResult, TParent = {}, TContext = {}, TArgs = {}> = ResolverFn<TResult, TParent, TContext, TArgs> | ResolverWithResolve<TResult, TParent, TContext, TArgs>;

export type ResolverFn<TResult, TParent, TContext, TArgs> = (
  parent: TParent,
  args: TArgs,
  context: TContext,
  info: GraphQLResolveInfo
) => Promise<TResult> | TResult;

export type SubscriptionSubscribeFn<TResult, TParent, TContext, TArgs> = (
  parent: TParent,
  args: TArgs,
  context: TContext,
  info: GraphQLResolveInfo
) => AsyncIterable<TResult> | Promise<AsyncIterable<TResult>>;

export type SubscriptionResolveFn<TResult, TParent, TContext, TArgs> = (
  parent: TParent,
  args: TArgs,
  context: TContext,
  info: GraphQLResolveInfo
) => TResult | Promise<TResult>;

export interface SubscriptionSubscriberObject<TResult, TKey extends string, TParent, TContext, TArgs> {
  subscribe: SubscriptionSubscribeFn<{ [key in TKey]: TResult }, TParent, TContext, TArgs>;
  resolve?: SubscriptionResolveFn<TResult, { [key in TKey]: TResult }, TContext, TArgs>;
}

export interface SubscriptionResolverObject<TResult, TParent, TContext, TArgs> {
  subscribe: SubscriptionSubscribeFn<any, TParent, TContext, TArgs>;
  resolve: SubscriptionResolveFn<TResult, any, TContext, TArgs>;
}

export type SubscriptionObject<TResult, TKey extends string, TParent, TContext, TArgs> =
  | SubscriptionSubscriberObject<TResult, TKey, TParent, TContext, TArgs>
  | SubscriptionResolverObject<TResult, TParent, TContext, TArgs>;

export type SubscriptionResolver<TResult, TKey extends string, TParent = {}, TContext = {}, TArgs = {}> =
  | ((...args: any[]) => SubscriptionObject<TResult, TKey, TParent, TContext, TArgs>)
  | SubscriptionObject<TResult, TKey, TParent, TContext, TArgs>;

export type TypeResolveFn<TTypes, TParent = {}, TContext = {}> = (
  parent: TParent,
  context: TContext,
  info: GraphQLResolveInfo
) => Maybe<TTypes> | Promise<Maybe<TTypes>>;

export type IsTypeOfResolverFn<T = {}, TContext = {}> = (obj: T, context: TContext, info: GraphQLResolveInfo) => boolean | Promise<boolean>;

export type NextResolverFn<T> = () => Promise<T>;

export type DirectiveResolverFn<TResult = {}, TParent = {}, TContext = {}, TArgs = {}> = (
  next: NextResolverFn<TResult>,
  parent: TParent,
  args: TArgs,
  context: TContext,
  info: GraphQLResolveInfo
) => TResult | Promise<TResult>;



/** Mapping between all available schema types and the resolvers types */
export type ResolversTypes = {
  Boolean: ResolverTypeWrapper<Scalars['Boolean']['output']>;
  DateTime: ResolverTypeWrapper<Scalars['DateTime']['output']>;
  Int: ResolverTypeWrapper<Scalars['Int']['output']>;
  LoginResponse: ResolverTypeWrapper<LoginResponse>;
  Mutation: ResolverTypeWrapper<{}>;
  Query: ResolverTypeWrapper<{}>;
  RefreshResponse: ResolverTypeWrapper<RefreshResponse>;
  RegisterResponse: ResolverTypeWrapper<RegisterResponse>;
  ResetResponse: ResolverTypeWrapper<ResetResponse>;
  String: ResolverTypeWrapper<Scalars['String']['output']>;
  UpdateProfileInput: UpdateProfileInput;
  UpdateUserInput: UpdateUserInput;
  User: ResolverTypeWrapper<User>;
  loginUserInput: LoginUserInput;
  refreshTokenInput: RefreshTokenInput;
  registerUserInput: RegisterUserInput;
  resetPwdConfInput: ResetPwdConfInput;
  resetPwdSentInput: ResetPwdSentInput;
};

/** Mapping between all available schema types and the resolvers parents */
export type ResolversParentTypes = {
  Boolean: Scalars['Boolean']['output'];
  DateTime: Scalars['DateTime']['output'];
  Int: Scalars['Int']['output'];
  LoginResponse: LoginResponse;
  Mutation: {};
  Query: {};
  RefreshResponse: RefreshResponse;
  RegisterResponse: RegisterResponse;
  ResetResponse: ResetResponse;
  String: Scalars['String']['output'];
  UpdateProfileInput: UpdateProfileInput;
  UpdateUserInput: UpdateUserInput;
  User: User;
  loginUserInput: LoginUserInput;
  refreshTokenInput: RefreshTokenInput;
  registerUserInput: RegisterUserInput;
  resetPwdConfInput: ResetPwdConfInput;
  resetPwdSentInput: ResetPwdSentInput;
};

export interface DateTimeScalarConfig extends GraphQLScalarTypeConfig<ResolversTypes['DateTime'], any> {
  name: 'DateTime';
}

export type LoginResponseResolvers<ContextType = any, ParentType extends ResolversParentTypes['LoginResponse'] = ResolversParentTypes['LoginResponse']> = {
  accessToken?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  message?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  refreshToken?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType, ContextType>;
};

export type MutationResolvers<ContextType = any, ParentType extends ResolversParentTypes['Mutation'] = ResolversParentTypes['Mutation']> = {
  deleteProfile?: Resolver<ResolversTypes['User'], ParentType, ContextType>;
  deleteUserById?: Resolver<ResolversTypes['User'], ParentType, ContextType, RequireFields<MutationDeleteUserByIdArgs, 'id'>>;
  loginUser?: Resolver<ResolversTypes['LoginResponse'], ParentType, ContextType, RequireFields<MutationLoginUserArgs, 'loginUserInput'>>;
  refreshToken?: Resolver<ResolversTypes['RefreshResponse'], ParentType, ContextType, RequireFields<MutationRefreshTokenArgs, 'refreshToken'>>;
  registerUser?: Resolver<ResolversTypes['RegisterResponse'], ParentType, ContextType, RequireFields<MutationRegisterUserArgs, 'registerUserInput'>>;
  resetPwdConf?: Resolver<ResolversTypes['LoginResponse'], ParentType, ContextType, RequireFields<MutationResetPwdConfArgs, 'resetPwdConfInput'>>;
  resetPwdSent?: Resolver<ResolversTypes['ResetResponse'], ParentType, ContextType, RequireFields<MutationResetPwdSentArgs, 'resetPwdSentInput'>>;
  updateProfile?: Resolver<ResolversTypes['User'], ParentType, ContextType, RequireFields<MutationUpdateProfileArgs, 'updateProfileInput'>>;
  updateUserById?: Resolver<ResolversTypes['User'], ParentType, ContextType, RequireFields<MutationUpdateUserByIdArgs, 'updateUserInput'>>;
  verifyRegister?: Resolver<ResolversTypes['LoginResponse'], ParentType, ContextType, RequireFields<MutationVerifyRegisterArgs, 'verificationToken'>>;
};

export type QueryResolvers<ContextType = any, ParentType extends ResolversParentTypes['Query'] = ResolversParentTypes['Query']> = {
  getAllUsers?: Resolver<Array<ResolversTypes['User']>, ParentType, ContextType>;
  getProfile?: Resolver<ResolversTypes['User'], ParentType, ContextType>;
  getUserById?: Resolver<ResolversTypes['User'], ParentType, ContextType, RequireFields<QueryGetUserByIdArgs, 'id'>>;
};

export type RefreshResponseResolvers<ContextType = any, ParentType extends ResolversParentTypes['RefreshResponse'] = ResolversParentTypes['RefreshResponse']> = {
  accessToken?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  message?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  refreshToken?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType, ContextType>;
};

export type RegisterResponseResolvers<ContextType = any, ParentType extends ResolversParentTypes['RegisterResponse'] = ResolversParentTypes['RegisterResponse']> = {
  message?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  verificationToken?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType, ContextType>;
};

export type ResetResponseResolvers<ContextType = any, ParentType extends ResolversParentTypes['ResetResponse'] = ResolversParentTypes['ResetResponse']> = {
  message?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  resetToken?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType, ContextType>;
};

export type UserResolvers<ContextType = any, ParentType extends ResolversParentTypes['User'] = ResolversParentTypes['User']> = {
  createdAt?: Resolver<ResolversTypes['DateTime'], ParentType, ContextType>;
  email?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  firstName?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  id?: Resolver<ResolversTypes['Int'], ParentType, ContextType>;
  lastName?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  role?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  updatedAt?: Resolver<ResolversTypes['DateTime'], ParentType, ContextType>;
  verified?: Resolver<ResolversTypes['Boolean'], ParentType, ContextType>;
  whatsapp?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType, ContextType>;
};

export type Resolvers<ContextType = any> = {
  DateTime?: GraphQLScalarType;
  LoginResponse?: LoginResponseResolvers<ContextType>;
  Mutation?: MutationResolvers<ContextType>;
  Query?: QueryResolvers<ContextType>;
  RefreshResponse?: RefreshResponseResolvers<ContextType>;
  RegisterResponse?: RegisterResponseResolvers<ContextType>;
  ResetResponse?: ResetResponseResolvers<ContextType>;
  User?: UserResolvers<ContextType>;
};

